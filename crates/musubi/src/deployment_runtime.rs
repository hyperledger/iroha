//! Presentation-free contract compilation and durable native deployment.
//!
//! Callers supply the exact SDK configuration, alias scope, private journal root and cache root.
//! This boundary never discovers a wallet, network configuration, cache location or signing
//! material from a project or the operating-system user cache.
use crate::archive_fetch::PreparedProductionSorafsArchiveTransportV1;
use eyre::{Result, WrapErr as _, bail, eyre};
use iroha::config::Config;
use iroha_contract_deploy::{
    DeploymentError, DeploymentPreflight, DeploymentProgress, DeploymentReceipt, DeploymentRequest,
    DeploymentService, JournalDisposition, MAX_DEPLOYMENT_ARTIFACT_BYTES, PreparedDeployment,
};
use iroha_data_model::{
    account::address::ChainDiscriminantGuard, smart_contract::ContractAlias,
    transaction::FeePaymentIntent,
};
use iroha_fs::{PrivateDirectory, PublishMode};
use kotodama_lang::{
    compiler::CompilerOptions,
    driver::{BuildDriver, discover_source_link_request},
    session::CompilerSession,
};
use std::path::{Path, PathBuf};

/// Explicit contract input; source and bytecode require no project manifest.
#[derive(Clone, Debug)]
pub enum ContractInput {
    /// A Kotodama root and its explicitly declared local includes.
    Source(PathBuf),
    /// A complete, self-describing IVM `.to` artifact.
    Bytecode(PathBuf),
    /// A Musubi package or workspace with canonical dependency resolution.
    Package {
        /// Explicit package/workspace manifest path.
        manifest: PathBuf,
        /// Exact package selector, required when workspace selection is ambiguous.
        package: Option<String>,
        /// Declared target, required when more than one target is selected.
        contract: Option<String>,
        /// Reject changes to the existing dependency lock.
        locked: bool,
    },
}

impl ContractInput {
    /// Select source, bytecode or an explicit Musubi package from one user-supplied path.
    /// This inexpensive filesystem check runs before provisioning; the build still authenticates
    /// every input when it reads the source, artifact or package graph.
    ///
    /// # Errors
    /// Rejects missing or nonregular inputs, missing package manifests, package selectors on
    /// standalone files and unsupported file names.
    pub fn from_path(
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
                manifest,
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
                    Ok(Self::Source(path.to_path_buf()))
                } else {
                    Ok(Self::Bytecode(path.to_path_buf()))
                }
            }
            _ if path.file_name().is_some_and(|name| name == "Musubi.toml") => Ok(Self::Package {
                manifest: path.to_path_buf(),
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
            ContractInput::Bytecode(path) => BuiltArtifact::from_bytes(
                iroha_fs::read_regular(path, MAX_DEPLOYMENT_ARTIFACT_BYTES)
                    .wrap_err("read exact contract bytecode")?
                    .to_vec(),
            ),
            ContractInput::Source(path) => {
                let source = path.canonicalize().wrap_err("resolve Kotodama source")?;
                let root = source
                    .parent()
                    .ok_or_else(|| eyre!("source has no parent"))?;
                let graph = discover_source_link_request(&source, root, Vec::new(), Vec::new())
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
                BuiltArtifact::from_bytes(output.artifact)
            }
            ContractInput::Package {
                manifest,
                package,
                contract,
                locked,
            } => crate::command::build_runtime_package(
                &self.config,
                &self.cache_root,
                self.build_registry.as_ref(),
                self.registry_resolver.as_deref(),
                manifest,
                package.as_deref(),
                contract.as_deref(),
                *locked,
                self.archive_transport.clone(),
            ),
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
        if let Some(journal) = session.current_journal()? {
            let retained = service.retained_preflight(&journal)?;
            validate_journal_location(
                &self.config,
                session
                    .writer
                    .path()
                    .parent()
                    .expect("runtime slot has root"),
                &journal,
                &retained.contract_alias,
                &plan_journal_id(&retained)?,
            )?;
            let same_input =
                retained.code_hash == artifact.code_hash && retained.contract_alias == alias;
            let disposition = if same_input {
                after_review(&retained, review, || Ok(service.inspect_journal(&journal)?))?
            } else {
                service.inspect_journal(&journal)?
            };
            match disposition {
                JournalDisposition::Pending { .. } if same_input => {
                    if retained
                        .fee_quotes
                        .iter()
                        .any(|quote| !fee_payment.has_same_payer_and_gas_bound(&quote.intent))
                    {
                        bail!(
                            "pending deployment uses a different fee payer or gas bound; resume its exact journal: {}",
                            journal.display()
                        );
                    }
                    let receipt = service
                        .resume(&journal, progress)
                        .map_err(|error| journal_failure(error, &journal))?;
                    return Ok(DeploymentRun { receipt, journal });
                }
                JournalDisposition::Pending { .. } => {
                    bail!(
                        "an earlier deployment has different unresolved artifact or alias inputs; resume its exact journal: {}",
                        journal.display()
                    );
                }
                JournalDisposition::Completed(_) if same_input => {
                    let receipt =
                        service
                            .current_completed_receipt(&journal)?
                            .ok_or_else(|| {
                                eyre!("completed deployment lost its authenticated receipt")
                            })?;
                    return Ok(DeploymentRun { receipt, journal });
                }
                JournalDisposition::Completed(_)
                | JournalDisposition::Failed(_)
                | JournalDisposition::Cancelled(_) => {}
            }
        }
        let prepared = service.prepare(&DeploymentRequest {
            artifact: artifact.bytes,
            alias,
            fee_payment,
            governance_approvers: Vec::new(),
        })?;
        review(prepared.preflight())?;
        let journal = session.persist(&service, &prepared)?;
        let receipt = service
            .execute(&prepared, &journal, progress)
            .map_err(|error| journal_failure(error, &journal))?;
        Ok(DeploymentRun { receipt, journal })
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
        let retained = journal
            .canonicalize()
            .wrap_err("resolve exact deployment journal")?;
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
        let _session = DeploymentSlot::open(slot)?;
        let service = DeploymentService::new(self.config.clone())?;
        let retained_preflight = service.retained_preflight(&retained)?;
        validate_journal_location(
            &self.config,
            &root,
            &retained,
            &retained_preflight.contract_alias,
            &plan_journal_id(&retained_preflight)?,
        )?;
        let receipt = after_review(&retained_preflight, review, || {
            service
                .resume(&retained, progress)
                .map_err(|error| journal_failure(error, &retained))
        })?;
        Ok(DeploymentRun {
            receipt,
            journal: retained,
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
        let writer = PrivateDirectory::open(&slot)?;
        let lock = writer.open_read("deployment.lock")?;
        lock.try_lock()
            .wrap_err("deployment target is already in use")?;
        writer.revalidate()?;
        let session = DeploymentSlot {
            writer,
            _lock: lock,
        };
        let journal = session
            .current_journal()?
            .ok_or_else(|| eyre!("contract alias has no retained deployment"))?;
        let service = DeploymentService::new(self.config.clone())?;
        let preflight = service.retained_preflight(&journal)?;
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
        let contract = service.current_completed_contract(&journal)?;
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
    let _profile = ChainDiscriminantGuard::enter(config.account_chain_discriminant);
    let identity = format!(
        "iroha.contract-deployment-slot.v1\n{}\n{}\n{}\n{}",
        config.network_id, config.account_chain_discriminant, config.account, alias
    );
    root.join(blake3::hash(identity.as_bytes()).to_hex().as_str())
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

/// One locked deployment target, also used by the existing package command adapter.
pub(crate) struct DeploymentSlot {
    writer: PrivateDirectory,
    _lock: std::fs::File,
}
impl DeploymentSlot {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let writer = PrivateDirectory::open_or_create(path)?;
        let lock = writer.open_lock("deployment.lock")?;
        lock.try_lock()
            .wrap_err("deployment target is already in use")?;
        writer.revalidate()?;
        Ok(Self {
            writer,
            _lock: lock,
        })
    }

    pub(crate) fn ensure_previous_terminal(&self, service: &DeploymentService) -> Result<()> {
        let Some(journal) = self.current_journal()? else {
            return Ok(());
        };
        if matches!(
            service.inspect_journal(&journal)?,
            JournalDisposition::Pending { .. }
        ) {
            bail!(
                "an earlier deployment is unresolved; resume its exact journal: {}",
                journal.display()
            );
        }
        Ok(())
    }

    pub(crate) fn current_journal(&self) -> Result<Option<PathBuf>> {
        let bytes = match self.writer.read("active-journal", 64) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let id = std::str::from_utf8(&bytes)?;
        validate_journal_id(id)?;
        Ok(Some(self.writer.path().join(id)))
    }

    pub(crate) fn persist(
        &self,
        service: &DeploymentService,
        prepared: &PreparedDeployment,
    ) -> Result<PathBuf> {
        let id = plan_journal_id(prepared.preflight())?;
        let journal = self.writer.path().join(&id);
        service.persist(prepared, &journal)?;
        self.writer
            .write_atomic("active-journal", id.as_bytes(), PublishMode::Replace)?;
        Ok(journal)
    }
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

    const SOURCE: &str = "seiyaku Coffee { view fn quote(int cups) -> int { return cups * 10; } }";

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
        fs::write(&bytecode, b"build validates the actual bytes")?;
        assert!(ContractInput::from_path(temp.path(), None, None, false).is_err());
        assert!(ContractInput::from_path(&manifest, None, None, false).is_err());
        fs::write(&manifest, "manifest-version = 1")?;
        assert!(matches!(
            ContractInput::from_path(&source, None, None, false)?,
            ContractInput::Source(_)
        ));
        assert!(matches!(
            ContractInput::from_path(&bytecode, None, None, false)?,
            ContractInput::Bytecode(_)
        ));
        assert!(
            matches!(ContractInput::from_path(temp.path(), Some("demo/coffee".into()), Some("coffee".into()), true)?, ContractInput::Package { manifest, locked: true, .. } if manifest == temp.path().join("Musubi.toml"))
        );
        assert!(matches!(
            ContractInput::from_path(&manifest, None, None, false)?,
            ContractInput::Package { .. }
        ));
        let source_named_directory = temp.path().join("package.ko");
        fs::create_dir(&source_named_directory)?;
        assert!(ContractInput::from_path(&source_named_directory, None, None, false).is_err());
        fs::write(
            source_named_directory.join("Musubi.toml"),
            "manifest-version = 1",
        )?;
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

    fn config() -> Config {
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
        assert!(!slot.join("active-journal").exists());
        assert_eq!(directory.read("sentinel", 8)?.as_slice(), b"original");
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
        let built = runtime.build(&ContractInput::Source(source))?;
        assert_eq!(built.name(), "Coffee");
        let bytecode = temp.path().join("contract.to");
        fs::write(&bytecode, built.bytes())?;
        let loaded = runtime.build(&ContractInput::Bytecode(bytecode))?;
        assert_eq!(loaded.bytes(), built.bytes());
        assert!(!temp.path().join("journals").exists());
        assert!(!temp.path().join("explicit-build-cache").exists());
        assert!(!temp.path().join("Musubi.lock").exists());
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
        let input = |locked| ContractInput::Package {
            manifest: manifest.clone(),
            package: None,
            contract: None,
            locked,
        };
        assert!(runtime.build(&input(true)).is_err());
        let artifact = runtime.build(&input(false))?;
        assert_eq!(artifact.name(), "Coffee");
        assert_eq!(runtime.build(&input(true))?.bytes(), artifact.bytes());
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
            .build(&ContractInput::Package {
                manifest,
                package: None,
                contract: None,
                locked: false,
            })
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
        let path = temp.path().join("slot");
        let session = DeploymentSlot::open(&path)?;
        assert!(DeploymentSlot::open(&path).is_err());
        let service = DeploymentService::new(config())?;
        session.ensure_previous_terminal(&service)?;
        session
            .writer
            .write_atomic("active-journal", b"../escape", PublishMode::Replace)?;
        assert!(session.ensure_previous_terminal(&service).is_err());
        drop(session);
        assert!(DeploymentSlot::open(&path).is_ok());
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
            &ContractInput::Source(source),
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
